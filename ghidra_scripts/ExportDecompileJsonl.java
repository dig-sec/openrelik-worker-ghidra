import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportDecompileJsonl extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No active program available");
        }

        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "Usage: ExportDecompileJsonl.java <output-path> [entrypoints|all] [timeout-seconds]"
            );
        }

        Path outputPath = Path.of(args[0]);
        String modeArg = args.length > 1 ? args[1].trim().toLowerCase() : "entrypoints";
        int timeoutSeconds = args.length > 2 ? parseTimeout(args[2]) : 600;

        // Parse mode: "focused" or "focused:80" (with optional limit)
        String mode;
        int focusedLimit = 80;
        if (modeArg.startsWith("focused")) {
            mode = "focused";
            if (modeArg.contains(":")) {
                try {
                    focusedLimit = Integer.parseInt(modeArg.split(":")[1]);
                    focusedLimit = Math.max(10, Math.min(500, focusedLimit));
                } catch (NumberFormatException ignored) {
                    // keep default
                }
            }
        } else {
            mode = modeArg;
        }

        if (!"entrypoints".equals(mode) && !"all".equals(mode) && !"focused".equals(mode)) {
            throw new IllegalArgumentException(
                "decompile mode must be one of: entrypoints, all, focused"
            );
        }

        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        List<Function> functions = collectTargetFunctions(mode, focusedLimit);
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        try (
            BufferedWriter writer = Files.newBufferedWriter(
                outputPath,
                StandardCharsets.UTF_8
            )
        ) {
            for (Function function : functions) {
                DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, monitor);

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", function.getName());
                row.put("entry_point", function.getEntryPoint().toString());
                row.put("signature", function.getPrototypeString(true, true));

                String status = "ok";
                String decompileText = "";
                String error = null;

                if (results == null) {
                    status = "failed";
                    error = "No decompile results";
                } else if (!results.decompileCompleted()) {
                    status = "failed";
                    error = results.getErrorMessage();
                } else if (results.getDecompiledFunction() != null) {
                    decompileText = results.getDecompiledFunction().getC();
                } else {
                    status = "failed";
                    error = "Missing decompiled function output";
                }

                row.put("status", status);
                row.put("decompile", decompileText);
                if (error != null && !error.isBlank()) {
                    row.put("error", error);
                }

                writer.write(toJson(row));
                writer.newLine();
            }
        } finally {
            decompiler.dispose();
        }

        println("Exported decompile JSONL: " + outputPath);
    }

    private int parseTimeout(String timeoutString) {
        try {
            int timeout = Integer.parseInt(timeoutString);
            return Math.max(1, timeout);
        } catch (NumberFormatException exception) {
            return 600;
        }
    }

    private List<Function> collectTargetFunctions(String mode, int focusedLimit) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        List<Function> functions = new ArrayList<>();

        if ("all".equals(mode)) {
            FunctionIterator iterator = functionManager.getFunctions(true);
            while (iterator.hasNext()) {
                functions.add(iterator.next());
            }
        } else if ("focused".equals(mode)) {
            functions = collectFocusedFunctions(focusedLimit);
        } else {
            // entrypoints mode
            Set<String> seenEntryPoints = new HashSet<>();
            AddressIterator entryPoints = currentProgram
                .getSymbolTable()
                .getExternalEntryPointIterator();

            while (entryPoints.hasNext()) {
                Address entryPoint = entryPoints.next();
                Function function = functionManager.getFunctionAt(entryPoint);
                if (function == null) {
                    function = functionManager.getFunctionContaining(entryPoint);
                }
                if (function != null && seenEntryPoints.add(function.getEntryPoint().toString())) {
                    functions.add(function);
                }
            }

            if (functions.isEmpty()) {
                FunctionIterator iterator = functionManager.getFunctions(true);
                if (iterator.hasNext()) {
                    functions.add(iterator.next());
                }
            }
        }

        functions.sort(Comparator.comparing(Function::getEntryPoint));
        return functions;
    }

    /**
     * Focused mode: collect entry-point functions plus top-N non-entrypoint
     * functions scored by code size, caller count, imported-API usage, and
     * string references.
     */
    private List<Function> collectFocusedFunctions(int maxCount) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        // 1. Collect entrypoint functions
        Set<String> entryPointAddresses = new HashSet<>();
        List<Function> entryFunctions = new ArrayList<>();
        AddressIterator epIterator = currentProgram
            .getSymbolTable()
            .getExternalEntryPointIterator();
        while (epIterator.hasNext()) {
            Address ep = epIterator.next();
            Function function = functionManager.getFunctionAt(ep);
            if (function == null) {
                function = functionManager.getFunctionContaining(ep);
            }
            if (function != null
                    && entryPointAddresses.add(function.getEntryPoint().toString())) {
                entryFunctions.add(function);
            }
        }

        // 2. Score every non-entrypoint function
        List<Function> allFunctions = new ArrayList<>();
        FunctionIterator iterator = functionManager.getFunctions(true);
        while (iterator.hasNext()) {
            allFunctions.add(iterator.next());
        }

        List<double[]> scores = new ArrayList<>();   // parallel with candidatesList
        List<Function> candidates = new ArrayList<>();
        for (Function f : allFunctions) {
            if (entryPointAddresses.contains(f.getEntryPoint().toString())) {
                continue;
            }
            double score = scoreFunctionSignificance(
                f, functionManager, referenceManager, listing
            );
            candidates.add(f);
            scores.add(new double[] { score });
        }

        // 3. Sort candidates by score descending
        Integer[] indices = new Integer[candidates.size()];
        for (int i = 0; i < indices.length; i++) {
            indices[i] = i;
        }
        java.util.Arrays.sort(
            indices,
            (a, b) -> Double.compare(scores.get(b)[0], scores.get(a)[0])
        );

        // 4. Merge: entrypoints first, then top-scored non-entrypoints
        List<Function> result = new ArrayList<>(entryFunctions);
        int remaining = maxCount - result.size();
        for (int i = 0; i < Math.min(remaining, indices.length); i++) {
            result.add(candidates.get(indices[i]));
        }

        println("Focused mode: " + entryFunctions.size() + " entrypoints + "
            + (result.size() - entryFunctions.size()) + " top-scored = "
            + result.size() + " total (limit " + maxCount + ")");

        return result;
    }

    /**
     * Compute a significance score for a function.
     * Higher score = more interesting for reverse-engineering analysis.
     * score = bodySize * (1 + callerCount) * (hasExternalCallee ? 3 : 1)
     *         * (hasStringRef ? 2 : 1)
     */
    private double scoreFunctionSignificance(
        Function function,
        FunctionManager functionManager,
        ReferenceManager referenceManager,
        Listing listing
    ) {
        long bodySize = function.getBody().getNumAddresses();

        // Count unique callers
        int callerCount = 0;
        Set<String> seenCallers = new HashSet<>();
        ReferenceIterator callerRefs = referenceManager.getReferencesTo(
            function.getEntryPoint()
        );
        while (callerRefs.hasNext()) {
            Reference ref = callerRefs.next();
            if (!ref.getReferenceType().isCall()) {
                continue;
            }
            Function caller = functionManager.getFunctionContaining(
                ref.getFromAddress()
            );
            if (caller != null
                    && seenCallers.add(caller.getEntryPoint().toString())) {
                callerCount++;
            }
        }

        // Check for external/imported callees and string references
        // (short-circuit: stop once both are found)
        boolean hasExternalCallee = false;
        boolean hasStringRef = false;
        InstructionIterator instructions = listing.getInstructions(
            function.getBody(), true
        );
        while (instructions.hasNext() && (!hasExternalCallee || !hasStringRef)) {
            Instruction instruction = instructions.next();
            Reference[] refs = referenceManager.getReferencesFrom(
                instruction.getAddress()
            );
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall() && !hasExternalCallee) {
                    Function callee = functionManager.getFunctionAt(
                        ref.getToAddress()
                    );
                    if (callee == null) {
                        callee = functionManager.getFunctionContaining(
                            ref.getToAddress()
                        );
                    }
                    if (callee != null) {
                        Function resolved = callee;
                        while (resolved.isThunk()) {
                            Function thunked = resolved.getThunkedFunction(false);
                            if (thunked == null) break;
                            resolved = thunked;
                        }
                        if (resolved.isExternal()) {
                            hasExternalCallee = true;
                        }
                    }
                } else if (!ref.getReferenceType().isCall() && !hasStringRef) {
                    Data data = listing.getDefinedDataAt(ref.getToAddress());
                    if (data != null) {
                        StringDataInstance sdi =
                            StringDataInstance.getStringDataInstance(data);
                        if (sdi != null && sdi.getStringValue() != null
                                && !sdi.getStringValue().isEmpty()) {
                            hasStringRef = true;
                        }
                    }
                }
            }
        }

        return bodySize
            * (1.0 + callerCount)
            * (hasExternalCallee ? 3.0 : 1.0)
            * (hasStringRef ? 2.0 : 1.0);
    }

    private String toJson(Object value) {
        if (value == null) {
            return "null";
        }

        if (value instanceof String) {
            return "\"" + jsonEscape((String) value) + "\"";
        }

        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }

        if (value instanceof Map<?, ?>) {
            StringBuilder builder = new StringBuilder();
            builder.append("{");

            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    builder.append(",");
                }
                first = false;
                builder
                    .append("\"")
                    .append(jsonEscape(String.valueOf(entry.getKey())))
                    .append("\":")
                    .append(toJson(entry.getValue()));
            }

            builder.append("}");
            return builder.toString();
        }

        if (value instanceof List<?>) {
            StringBuilder builder = new StringBuilder();
            builder.append("[");

            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) {
                    builder.append(",");
                }
                first = false;
                builder.append(toJson(item));
            }

            builder.append("]");
            return builder.toString();
        }

        return "\"" + jsonEscape(value.toString()) + "\"";
    }

    private String jsonEscape(String value) {
        StringBuilder builder = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\':
                    builder.append("\\\\");
                    break;
                case '"':
                    builder.append("\\\"");
                    break;
                case '\b':
                    builder.append("\\b");
                    break;
                case '\f':
                    builder.append("\\f");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04x", (int) character));
                    } else {
                        builder.append(character);
                    }
            }
        }
        return builder.toString();
    }
}

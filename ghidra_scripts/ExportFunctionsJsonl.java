import ghidra.app.script.GhidraScript;
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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportFunctionsJsonl extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No active program available");
        }

        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: ExportFunctionsJsonl.java <output-path>");
        }

        Path outputPath = Path.of(args[0]);
        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = functionManager.getFunctions(true);
        while (iterator.hasNext()) {
            functions.add(iterator.next());
        }
        functions.sort(Comparator.comparing(Function::getEntryPoint));

        try (
            BufferedWriter writer = Files.newBufferedWriter(
                outputPath,
                StandardCharsets.UTF_8
            )
        ) {
            for (Function function : functions) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", function.getName());
                row.put("entry_point", function.getEntryPoint().toString());
                row.put("size", function.getBody().getNumAddresses());
                row.put("signature", function.getPrototypeString(true, true));

                // Collect caller names
                List<String> callerNames = collectCallerNames(
                    function, functionManager, referenceManager
                );
                row.put("callers_count", callerNames.size());
                row.put("callers", callerNames);

                // Single-pass collection of callees, imported calls, and string refs
                Map<String, Object> callInfo = collectCallAndDataInfo(
                    function, functionManager, referenceManager, listing
                );
                @SuppressWarnings("unchecked")
                List<String> calleeNames = (List<String>) callInfo.get("callees");
                row.put("callees_count", calleeNames != null ? calleeNames.size() : 0);
                row.put("callees", callInfo.get("callees"));
                row.put("imported_calls", callInfo.get("imported_calls"));
                row.put("string_refs", callInfo.get("string_refs"));

                writer.write(toJson(row));
                writer.newLine();
            }
        }

        println("Exported functions JSONL: " + outputPath);
    }

    private List<String> collectCallerNames(
        Function function,
        FunctionManager functionManager,
        ReferenceManager referenceManager
    ) {
        Set<String> seen = new LinkedHashSet<>();
        ReferenceIterator references = referenceManager.getReferencesTo(function.getEntryPoint());
        while (references.hasNext()) {
            Reference reference = references.next();
            if (!reference.getReferenceType().isCall()) {
                continue;
            }
            Function caller = functionManager.getFunctionContaining(reference.getFromAddress());
            if (caller != null && !caller.getEntryPoint().equals(function.getEntryPoint())) {
                seen.add(caller.getName());
            }
        }
        return new ArrayList<>(seen);
    }

    /**
     * Single pass over a function's instructions to collect:
     * - callee function names
     * - imported/external API calls (resolved through thunks)
     * - referenced string literal values
     */
    private Map<String, Object> collectCallAndDataInfo(
        Function function,
        FunctionManager functionManager,
        ReferenceManager referenceManager,
        Listing listing
    ) {
        Set<String> calleeNames = new LinkedHashSet<>();
        Set<String> importedCalls = new LinkedHashSet<>();
        Set<String> stringRefs = new LinkedHashSet<>();

        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Reference[] references = referenceManager.getReferencesFrom(instruction.getAddress());

            for (Reference reference : references) {
                if (reference.getReferenceType().isCall()) {
                    Function callee = functionManager.getFunctionAt(reference.getToAddress());
                    if (callee == null) {
                        callee = functionManager.getFunctionContaining(reference.getToAddress());
                    }
                    if (callee != null) {
                        calleeNames.add(callee.getName());

                        // Resolve thunks to find the actual external/imported function
                        Function resolved = callee;
                        while (resolved.isThunk()) {
                            Function thunked = resolved.getThunkedFunction(false);
                            if (thunked == null) {
                                break;
                            }
                            resolved = thunked;
                        }
                        if (resolved.isExternal()) {
                            importedCalls.add(resolved.getName(true));
                        }
                    }
                } else {
                    // Non-call reference: check if target is a defined string
                    Data data = listing.getDefinedDataAt(reference.getToAddress());
                    if (data != null) {
                        StringDataInstance instance =
                            StringDataInstance.getStringDataInstance(data);
                        if (instance != null) {
                            String value = instance.getStringValue();
                            if (value != null && !value.isEmpty()
                                    && stringRefs.size() < 20) {
                                stringRefs.add(value);
                            }
                        }
                    }
                }
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("callees", new ArrayList<>(calleeNames));
        result.put("imported_calls", new ArrayList<>(importedCalls));
        result.put("string_refs", new ArrayList<>(stringRefs));
        return result;
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

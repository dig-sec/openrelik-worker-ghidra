import ghidra.app.script.GhidraScript;
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
                row.put(
                    "callers_count",
                    countCallers(function, functionManager, referenceManager)
                );
                row.put(
                    "callees_count",
                    countCallees(function, functionManager, referenceManager, listing)
                );

                writer.write(toJson(row));
                writer.newLine();
            }
        }

        println("Exported functions JSONL: " + outputPath);
    }

    private int countCallers(
        Function function,
        FunctionManager functionManager,
        ReferenceManager referenceManager
    ) {
        Set<String> callerEntryPoints = new HashSet<>();

        ReferenceIterator references = referenceManager.getReferencesTo(function.getEntryPoint());
        while (references.hasNext()) {
            Reference reference = references.next();
            if (!reference.getReferenceType().isCall()) {
                continue;
            }

            Function caller = functionManager.getFunctionContaining(reference.getFromAddress());
            if (caller != null) {
                callerEntryPoints.add(caller.getEntryPoint().toString());
            }
        }

        return callerEntryPoints.size();
    }

    private int countCallees(
        Function function,
        FunctionManager functionManager,
        ReferenceManager referenceManager,
        Listing listing
    ) {
        Set<String> calleeEntryPoints = new HashSet<>();

        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Reference[] references = referenceManager.getReferencesFrom(instruction.getAddress());
            for (Reference reference : references) {
                if (!reference.getReferenceType().isCall()) {
                    continue;
                }

                Function callee = functionManager.getFunctionAt(reference.getToAddress());
                if (callee == null) {
                    callee = functionManager.getFunctionContaining(reference.getToAddress());
                }
                if (callee != null) {
                    calleeEntryPoints.add(callee.getEntryPoint().toString());
                }
            }
        }

        return calleeEntryPoints.size();
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

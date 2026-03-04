import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

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
        String mode = args.length > 1 ? args[1].trim().toLowerCase() : "entrypoints";
        int timeoutSeconds = args.length > 2 ? parseTimeout(args[2]) : 600;

        if (!"entrypoints".equals(mode) && !"all".equals(mode)) {
            throw new IllegalArgumentException("decompile mode must be one of: entrypoints, all");
        }

        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        List<Function> functions = collectTargetFunctions(mode);
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

    private List<Function> collectTargetFunctions(String mode) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        List<Function> functions = new ArrayList<>();

        if ("all".equals(mode)) {
            FunctionIterator iterator = functionManager.getFunctions(true);
            while (iterator.hasNext()) {
                functions.add(iterator.next());
            }
        } else {
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

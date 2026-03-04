import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.DefinedDataIterator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportStringsJson extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No active program available");
        }

        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: ExportStringsJson.java <output-path>");
        }

        Path outputPath = Path.of(args[0]);
        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        List<Map<String, Object>> strings = new ArrayList<>();
        ReferenceManager referenceManager = currentProgram.getReferenceManager();

        DefinedDataIterator iterator = DefinedDataIterator.definedData(currentProgram);
        while (iterator.hasNext()) {
            Data data = iterator.next();
            StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
            // In Ghidra 12.x getStringDataInstance() never returns null; use isValid()
            if (instance == null || !instance.isValid()) {
                continue;
            }
            String value = instance.getStringValue();
            if (value == null) {
                continue;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", data.getAddress().toString());
            row.put("value", value);
            row.put("ref_count", referenceManager.getReferenceCountTo(data.getAddress()));
            strings.add(row);
        }

        strings.sort(Comparator.comparing(row -> (String) row.get("address")));

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("count", strings.size());
        root.put("strings", strings);

        Files.writeString(
            outputPath,
            toJson(root) + System.lineSeparator(),
            StandardCharsets.UTF_8
        );

        println("Exported strings JSON: " + outputPath);
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

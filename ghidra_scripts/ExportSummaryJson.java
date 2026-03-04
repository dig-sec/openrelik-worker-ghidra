import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefinedStringIterator;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportSummaryJson extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No active program available");
        }

        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "Usage: ExportSummaryJson.java <output-path> [ghidra-version] [scripts-git-sha]"
            );
        }

        String outputPathArg = args[0];
        String ghidraVersion = args.length > 1 ? args[1] : "unknown";
        String scriptsGitSha = args.length > 2 ? args[2] : "unknown";

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("ghidra_version", ghidraVersion);
        summary.put("scripts_git_sha", scriptsGitSha);
        summary.put("program_name", currentProgram.getName());
        summary.put("executable_path", currentProgram.getExecutablePath());
        summary.put("language_id", currentProgram.getLanguageID().toString());
        summary.put("compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        summary.put("md5", computeDigest(currentProgram.getExecutablePath(), "MD5"));
        summary.put("sha256", computeDigest(currentProgram.getExecutablePath(), "SHA-256"));
        summary.put("entry_points", collectEntryPoints(currentProgram.getSymbolTable()));
        summary.put("imports", collectImports(currentProgram));
        summary.put("exports", collectExports(currentProgram.getSymbolTable()));
        summary.put("segments", collectSegments(currentProgram));
        summary.put("function_count", currentProgram.getFunctionManager().getFunctionCount());
        summary.put("strings_count", countDefinedStrings(currentProgram));

        Path outputPath = Path.of(outputPathArg);
        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Files.writeString(
            outputPath,
            toJson(summary) + System.lineSeparator(),
            StandardCharsets.UTF_8
        );

        println("Exported summary JSON: " + outputPathArg);
    }

    // Ghidra 12+ compat: use DefinedStringIterator.forProgram() instead of
    // the removed DefinedDataIterator.definedData() API.
    private int countDefinedStrings(Program program) {
        int stringsCount = 0;
        for (Data data : DefinedStringIterator.forProgram(program, null)) {
            StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
            if (instance != null && instance.getStringValue() != null) {
                stringsCount += 1;
            }
        }
        return stringsCount;
    }

    private List<String> collectEntryPoints(SymbolTable symbolTable) {
        List<String> entryPoints = new ArrayList<>();
        AddressIterator iterator = symbolTable.getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            entryPoints.add(iterator.next().toString());
        }
        entryPoints.sort(String::compareTo);
        return entryPoints;
    }

    private List<Map<String, Object>> collectImports(Program program) {
        List<Map<String, Object>> imports = new ArrayList<>();
        ExternalManager externalManager = program.getExternalManager();

        String[] libraries = externalManager.getExternalLibraryNames();
        Arrays.sort(libraries);

        for (String library : libraries) {
            ExternalLocationIterator locations = externalManager.getExternalLocations(library);
            while (locations.hasNext()) {
                ExternalLocation location = locations.next();

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("library", library);
                row.put("symbol", location.toString());
                imports.add(row);
            }
        }

        imports.sort(
            (left, right) -> {
                int libraryCompare = ((String) left.get("library"))
                    .compareTo((String) right.get("library"));
                if (libraryCompare != 0) {
                    return libraryCompare;
                }
                return ((String) left.get("symbol"))
                    .compareTo((String) right.get("symbol"));
            }
        );

        return imports;
    }

    private List<Map<String, Object>> collectExports(SymbolTable symbolTable) {
        List<Map<String, Object>> exports = new ArrayList<>();
        AddressIterator iterator = symbolTable.getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            Address address = iterator.next();
            Symbol symbol = symbolTable.getPrimarySymbol(address);

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", address.toString());
            row.put("name", symbol == null ? address.toString() : symbol.getName(true));
            exports.add(row);
        }

        exports.sort(Comparator.comparing(row -> (String) row.get("address")));
        return exports;
    }

    private List<Map<String, Object>> collectSegments(Program program) {
        List<Map<String, Object>> segments = new ArrayList<>();
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        Arrays.sort(blocks, Comparator.comparing(block -> block.getStart()));

        for (MemoryBlock block : blocks) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", block.getName());
            row.put("start", block.getStart().toString());
            row.put("end", block.getEnd().toString());
            row.put("size", block.getSize());
            row.put("read", block.isRead());
            row.put("write", block.isWrite());
            row.put("execute", block.isExecute());
            row.put("volatile", block.isVolatile());
            segments.add(row);
        }

        return segments;
    }

    private String computeDigest(String filePath, String algorithm) {
        if (filePath == null || filePath.isBlank()) {
            return null;
        }

        Path path = Path.of(filePath);
        if (!Files.exists(path) || !Files.isReadable(path)) {
            return null;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            try (InputStream stream = Files.newInputStream(path)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = stream.read(buffer)) > 0) {
                    digest.update(buffer, 0, read);
                }
            }
            return toHex(digest.digest());
        } catch (NoSuchAlgorithmException | IOException exception) {
            return null;
        }
    }

    private String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
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

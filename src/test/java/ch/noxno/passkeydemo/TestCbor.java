package ch.noxno.passkeydemo;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * The smallest canonical CBOR writer that can build a WebAuthn attestationObject and a COSE key.
 * Test-only: maps are written in the order they are given, which is already the canonical order
 * for the fixed key sets used here.
 */
final class TestCbor {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    byte[] toByteArray() {
        return out.toByteArray();
    }

    TestCbor writeInt(long value) {
        if (value >= 0) {
            writeTypeAndLength(0, value);
        } else {
            writeTypeAndLength(1, -1 - value);
        }
        return this;
    }

    TestCbor writeBytes(byte[] value) {
        writeTypeAndLength(2, value.length);
        out.writeBytes(value);
        return this;
    }

    TestCbor writeText(String value) {
        byte[] raw = value.getBytes(StandardCharsets.UTF_8);
        writeTypeAndLength(3, raw.length);
        out.writeBytes(raw);
        return this;
    }

    TestCbor writeArrayHeader(int size) {
        writeTypeAndLength(4, size);
        return this;
    }

    TestCbor writeMapHeader(int size) {
        writeTypeAndLength(5, size);
        return this;
    }

    TestCbor writeRaw(byte[] alreadyEncoded) {
        out.writeBytes(alreadyEncoded);
        return this;
    }

    private void writeTypeAndLength(int majorType, long length) {
        int high = majorType << 5;
        if (length < 24) {
            out.write(high | (int) length);
        } else if (length < 256) {
            out.write(high | 24);
            out.write((int) length);
        } else if (length < 65536) {
            out.write(high | 25);
            out.write((int) (length >> 8));
            out.write((int) (length & 0xff));
        } else {
            out.write(high | 26);
            out.write((int) (length >> 24) & 0xff);
            out.write((int) (length >> 16) & 0xff);
            out.write((int) (length >> 8) & 0xff);
            out.write((int) length & 0xff);
        }
    }

    /** COSE_Key {1: 2, 3: -7, -1: 1, -2: x, -3: y} in CTAP2 canonical order. */
    static byte[] coseKeyEs256(byte[] x, byte[] y) {
        TestCbor cbor = new TestCbor();
        cbor.writeMapHeader(5);
        cbor.writeInt(1).writeInt(2);
        cbor.writeInt(3).writeInt(-7);
        cbor.writeInt(-1).writeInt(1);
        cbor.writeInt(-2).writeBytes(x);
        cbor.writeInt(-3).writeBytes(y);
        return cbor.toByteArray();
    }

    /** attestationObject {"fmt": fmt, "attStmt": {...}, "authData": bytes}. */
    static byte[] attestationObject(String fmt, Map<String, Object> attStmt, byte[] authData) {
        TestCbor cbor = new TestCbor();
        cbor.writeMapHeader(3);
        cbor.writeText("fmt").writeText(fmt);
        cbor.writeText("attStmt").writeMapHeader(attStmt.size());
        for (Map.Entry<String, Object> entry : attStmt.entrySet()) {
            cbor.writeText(entry.getKey());
            Object value = entry.getValue();
            if (value instanceof Integer intValue) {
                cbor.writeInt(intValue);
            } else if (value instanceof byte[] bytes) {
                cbor.writeBytes(bytes);
            } else if (value instanceof List<?> list) {
                cbor.writeArrayHeader(list.size());
                for (Object element : list) {
                    cbor.writeBytes((byte[]) element);
                }
            } else {
                throw new IllegalArgumentException("unsupported attStmt value " + value);
            }
        }
        cbor.writeText("authData").writeBytes(authData);
        return cbor.toByteArray();
    }
}

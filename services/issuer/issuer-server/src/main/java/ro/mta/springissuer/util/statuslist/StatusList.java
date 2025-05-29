package ro.mta.springissuer.util.statuslist;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.BitSet;
import java.util.zip.Deflater;

/**
 * Clasa care reprezintă un status list pentru verifiable credentials.
 * Daca bit-ul corespunzator id-ului credentialului este setat pe 1, atunci acesta este revocat.
 */
@Component
public class StatusList {
    @Value("${revocation.list.size}")
    private int CREDENTIAL_ID_MAX;

    private BitSet bitSet;


    public StatusList() {
        this.bitSet = new BitSet(CREDENTIAL_ID_MAX);
    }


    /**
     * Schimba statusul unui credențial din listă.
     * @param index index-ul credențialului
     * @param status statutul dorit (1 înseamnă recovat)
     */
    public void setStatus(BigInteger index, boolean status) {
        if (index.compareTo(BigInteger.valueOf(this.CREDENTIAL_ID_MAX)) >= 0) {
            throw new IllegalArgumentException("Index is out of bounds");
        }
        bitSet.set(index.intValue(), status);
    }

    /**
     * Returnează status list-ul compresat folosind zlib cu cea mai bună rată de compresie.
     * @return status list-ul compresat.
     */
    public byte[] getStatusListCompressed() {

        bitSet.set(this.CREDENTIAL_ID_MAX, true);

        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(bitSet.toByteArray());
        deflater.finish();

        byte[] output = new byte[bitSet.toByteArray().length + (bitSet.toByteArray().length / 10) + 12];
        int compressedDataLength = deflater.deflate(output);

        if (compressedDataLength <= 0) {
            throw new RuntimeException("Error compressing status list");
        }

        return output;
    }

    /**
     * @return dimensiunea în biți a status list-ului
     */
    public int getSize() {
        return this.CREDENTIAL_ID_MAX;
    }


}

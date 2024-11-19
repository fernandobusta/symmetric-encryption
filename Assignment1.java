import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Assignment1 {

    private static final Logger logger = Logger.getLogger(Assignment1.class.getName());
    private static boolean modeGenerate = false;
    private static boolean modeTest = false;

    public BigInteger pPrimeModulus;
    public BigInteger gGenerator;
    public BigInteger APublicShared;
    public BigInteger bSecretValue;
    public BigInteger BPublicShared;
    public BigInteger sSharedSecret;
    public byte[] kAESkey;

    /**
     * Constructor for Assignment1
     * @param pPrimeModulusHex -> Prime modulus p in hexadecimal
     * @param gGeneratorHex -> Generator g in hexadecimal
     * @param APublicSharedHex -> Public shared value A in hexadecimal
     */
    public Assignment1(String pPrimeModulusHex, String gGeneratorHex, String APublicSharedHex) {
        pPrimeModulus = new BigInteger(pPrimeModulusHex, 16);
        gGenerator = new BigInteger(gGeneratorHex, 16);
        APublicShared = new BigInteger(APublicSharedHex, 16);
    }

    /**
     * Generate b: secret value
     * @return b -> random 1023-bit integer
     */
    public BigInteger generateSecretValue() {
        if (modeGenerate) {
            SecureRandom secureRandom = new SecureRandom();
            bSecretValue = new BigInteger(1023, secureRandom);
            saveValueToFile(bSecretValue, "b.txt");
            return bSecretValue;
        }
        // Secret Value b already generated 
        bSecretValue = new BigInteger("37b75e77750c6ca69152e428b0966562b7ec45a8a54c3bcc584e8803391d3f19efcbabbe4460068a19e8fa6eb0a4a48eff3bfa7aa33ebc81f86f34598d1c180f3c1f4f8bc5ec4539f74746ddb441da365417f27eba3f7ac1660233bbec224206031bcdca0e5a0a659f95d45c8ee90b91b839c33c54febc00304e4d64c3740422", 16);

        return bSecretValue;
    }

    /**
     * Generate B: public shared value
     * Using left-to-right square and multiply algorithm
     * @return B -> g^b (mod p)
     */
    public BigInteger generatePublicSharedValue() {
        if (modeGenerate) {
            BPublicShared = squareAndMultiply(gGenerator, bSecretValue, pPrimeModulus);
            saveValueToFile(BPublicShared, "DH.txt");
            return BPublicShared;
        }
        BPublicShared = readValueFromFile("DH.txt");
        return BPublicShared;
    }

    /**
     * Generate s: shared secret
     * @return s -> A^b (mod p)
     */
    public BigInteger generateSharedSecret() {
        sSharedSecret = squareAndMultiply(APublicShared, bSecretValue, pPrimeModulus);
        return sSharedSecret;
    }

    /**
     * Generate AES key
     * @return kAESkey -> SHA-256 hash of shared secret s
     */
    public byte[] generateAESKey() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            kAESkey = digest.digest(sSharedSecret.toByteArray());
            return kAESkey;
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Error: {0}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Generate random 128-bit IV
     * @return ivParameterSpec -> random 128-bit IV
     */
    public IvParameterSpec generateIV() {
        if (modeGenerate) {
            byte[] iv = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            saveValueToFile(ivParameterSpec, "IV.txt");
            return ivParameterSpec;
        }
        // Read IV from file
        IvParameterSpec ivParameterSpec = new IvParameterSpec(readValueFromFile("IV.txt").toByteArray());
        return ivParameterSpec;
    }

    /**
     * Read the value from file
     * @param filename -> name of the file to read the value from
     * @return value -> BigInteger value read from the file
     */
    private BigInteger readValueFromFile(String filename) {
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(filename))) {
            String hexValue = bufferedReader.readLine();
            return new BigInteger(hexValue, 16);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error: {0}", e.getMessage());
            return null;
        }
    }

    /**
     * Save the value to file
     * @param value -> hexadecimal value to be saved
     * @param filename -> name of the file to save the value
     */
    private void saveValueToFile(Object value, String filename) {
        try (FileWriter fileWriter = new FileWriter(filename)) {
            if (value instanceof BigInteger bigInteger) {
                fileWriter.write(bigInteger.toString(16));
            } else if (value instanceof IvParameterSpec) {
                fileWriter.write(bytesToHex(((IvParameterSpec) value).getIV()));
            } else {
                throw new IllegalArgumentException("Invalid value type");
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error: {0}", e.getMessage());
        }
    }

    /**
     * Applies Square and Multiply algorithm, Left-to-right
     * @param base -> base value
     * @param exponent -> exponent value
     * @param modulus -> modulus value
     * @return BigInteger result from the modular exponentiation
     */
    private BigInteger squareAndMultiply(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        String binaryExponent = exponent.toString(2);
        for (char bit : binaryExponent.toCharArray()) {
            result = result.multiply(result).mod(modulus);
            if (bit == '1') {
                result = result.multiply(base).mod(modulus);
            }
        }
        return result;
    }

    /**
     * Encrypt the input file using AES/CBC
     * @param inputFile -> input file to be encrypted
     * @param key -> AES key
     * @return encrypted file
     */
    public byte[] encryptFile(String inputFile, byte[] key) throws Exception {
        // Read input file into byte array
        byte[] inputBytes = readFileToByteArray(inputFile);
        byte[] paddedBytes = applyPadding(inputBytes);
        // Setting the Cipher -> AES/CBC/NoPadding (already padded)
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        // Set the secret already created -> kAESkey
        SecretKeySpec sKeySpec = new SecretKeySpec(key, "AES");
        // Get the IV
        IvParameterSpec IV = generateIV();
        // Initialize the cipher with encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, IV);

        byte[] encyptedFile = cipher.doFinal(paddedBytes);
        return encyptedFile;
    }

    /**
     * Apply padding scheme to the input data
     * @param inputBytes -> input data
     * @return padded data
     */
    public byte[] applyPadding(byte[] inputBytes) {
        int blockSize = 16;
        int paddingLength = blockSize - (inputBytes.length % blockSize);
        // If the input length is already a multiple of the block size, add an extra block
        if (paddingLength == 0) {
            paddingLength = blockSize;
        }
        // Create a new array with the size of the original data plus the padding length
        byte[] paddedBytes = new byte[inputBytes.length + paddingLength];
        // Copy the original data to the new array
        System.arraycopy(inputBytes, 0, paddedBytes, 0, inputBytes.length);
        // Append a 1-bit (0x80) followed by 0-bits as padding
        paddedBytes[inputBytes.length] = (byte) 0x80;
        // The rest of the padding bytes are already 0 by default
        return paddedBytes;
    }

    /**
     * Read the file into byte array
     * @param filename -> name of the file to read
     * @return byte array of the file
     */
    private byte[] readFileToByteArray(String filename) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(filename)) {
            return fileInputStream.readAllBytes();
        }
    }

    /**
     * Convert byte array to hexadecimal string
     * @param bytes -> byte array to be converted
     * @return hexadecimal string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }   

    /**
     * Test the assignment
     */
    private void testAssignent() {
        // generate random secret value c, replacing a
        SecureRandom secureRandom = new SecureRandom();
        BigInteger cSecretValue = new BigInteger(1023, secureRandom);

        // Create his secret s by getting B^c (mod p) -- replaces ->  B^a (mod p)
        BigInteger hisNewSecretS = squareAndMultiply(BPublicShared, cSecretValue, pPrimeModulus);
        // Get g^c (mod p) = C -> public shared value replacing A
        BigInteger CPublicShared = squareAndMultiply(gGenerator, cSecretValue, pPrimeModulus);

        // Create my secret s from C^b (mod p)
        BigInteger myNewSecretS = squareAndMultiply(CPublicShared, bSecretValue, pPrimeModulus);

        logger.log(Level.INFO, "His shared Secret: {0}", hisNewSecretS.toString(16));
        logger.log(Level.INFO, "My shared Secret: {0}", myNewSecretS.toString(16));

        // Compare the two and log the result
        if (hisNewSecretS.equals(myNewSecretS)) {
            logger.log(Level.INFO, "=========== Shared Secret Matched");
        } else {
            logger.log(Level.INFO, "=========== Shared Secret Mismatched");
        }
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            // Check if the second argument is "generate"
            if (args.length > 1 && "generate".equalsIgnoreCase(args[1])) {
                // Change mode to generate
                modeGenerate = true;
                logger.log(Level.INFO, "Mode: Generate");
            } else if (args.length > 1 && "test".equalsIgnoreCase(args[1])){
                // Change mode to test
                modeTest = true;
                logger.log(Level.INFO, "Mode: Test");
            }
        }

        String pHex = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
        String gHex = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
        String AHex = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";
        Assignment1 assignment1 = new Assignment1(pHex, gHex, AHex);
        assignment1.generateSecretValue(); // Generate secret value b
        assignment1.generatePublicSharedValue(); // Generate public shared value B

        if (modeTest == true) {
            assignment1.testAssignent();
        } else {
            assignment1.generateSharedSecret(); // Generate shared secret s
            assignment1.generateAESKey(); // Generate AES key
            String inputFile = args[0];
            try {
                byte[] encrypteData = assignment1.encryptFile(inputFile, assignment1.kAESkey);
                System.out.println(assignment1.bytesToHex(encrypteData));
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }
}
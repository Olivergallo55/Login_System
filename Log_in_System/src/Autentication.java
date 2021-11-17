import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
 
public class Autentication {

	private static final int SALT_BYTES = 28;
	private static final int OUTPUT_SIZE_BYTES = 8;
	private static final int AMOUNT_OF_ITERATIONS = 1000;

	/**
	 * This method generates a random salt for the hashing algorithm to use in order
	 * to prevent password collision and rainbow tabling
	 * 
	 * @return salt a random byte sequence
	 */
	public byte[] generateSalt() {
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[SALT_BYTES];
		random.nextBytes(salt);
		return salt;
	}

	/**
	 * Convert the hash from a byte sequence to a hexadecimal string
	 * 
	 * @param hash is the given hashed password
	 * @return the converted hash
	 */
	private static String convertHashToString(byte[] hash) {
		StringBuilder hashCode = new StringBuilder(hash.length * 2);
		for (byte code : hash)
			hashCode.append(String.format("%02x", code));

		return hashCode.toString();
	}

	/**
	 * This method converts the password to a byte sequence, by putting 2 hex values
	 * in one byte in this kind of manner {1,2,3,4} -> {12,34}, which besides the
	 * conversion even saves space. These hex decimals are often represented as 0xC7
	 * to make it more clear that it is a hex. The left shifting is equal to *16 and
	 * only written as it is to make the code more readable.
	 * 
	 * @param password
	 * @return data
	 */
	private static byte[] convertHashToByte(String password) {
		int len = password.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(password.charAt(i), 16) << 4)
					+ Character.digit(password.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * Generate a hash in a hex string using the password.
	 * 
	 * @param password is the given password
	 * @return a converted hash and salt represented in a hex string
	 * @throws NoSuchAlgorithmException and InvalidKeySpecException
	 */
	public String generateHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] salt = generateSalt();
		byte[] hash = createPassword(password.toCharArray(), salt, AMOUNT_OF_ITERATIONS, SALT_BYTES);

		return convertHashToString(hash) + ":" + convertHashToString(salt);
	}

	/**
	 * This method creates a pbkdf2 hash algorithm to make the password saving more
	 * secure and harder to break. The algorithm hashes the password in a away that
	 * cannot be rehashed and obtained as regular plain text. After the hash have
	 * been created it converts into a string representation.
	 * 
	 * @param password
	 * @return the password in a string representation
	 * 
	 */
	public String generateHash(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] salt = generateSalt();
		byte[] hash = createPassword(password, salt, AMOUNT_OF_ITERATIONS, SALT_BYTES);
		return convertHashToString(hash) + ":" + convertHashToString(salt);
	}

	/**
	 * Validates the using hashing
	 * 
	 * @throws NoSuchAlgorithmException and InvalidKeySpecException
	 * @param password      is the given password
	 * @param validPassword is the correct password hash
	 * @return true if the two hashes are equal and false if they are not
	 */
	public boolean validateHash(char[] password, String validPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		String[] splitPassword = validPassword.split(":");
		byte[] hash = convertHashToByte(splitPassword[0]);
		byte[] salt = convertHashToByte(splitPassword[1]);
		byte[] finalPassword = createPassword(password, salt, AMOUNT_OF_ITERATIONS, hash.length);

		return slowEquals(hash, finalPassword);
	}

	/**
	 * This method checks if the two passwords given in a byte array are equal.
	 * Through this method the system can eliminate time branch delay that regular
	 * "==" operator gives, due this method a potential attacker wont be able to
	 * estimate a time difference between different passwords.
	 * 
	 * @param hash      is the input hashed password
	 * @param validHash is the correct hash
	 * @return true if the two byte arrays are exactly the same else false
	 */
	private boolean slowEquals(byte[] hash, byte[] validHash) {
		int difference = hash.length ^ validHash.length;
		for (int i = 0; i < hash.length && i < validHash.length; i++) {
			difference |= hash[i] ^ validHash[i];
		}
		return difference == 0 ? true : false;
	}

	/**
	 * Create the pbkfd2 algorithm that hashes the password so it cannot be rehashed
	 * and obtained as a plain text.
	 * 
	 * @throws NoSuchAlgorithmException and InvalidKeySpecException
	 * @param password   the password to hash
	 * @param salt       the salt
	 * @param iterations the amount of iteration the algorithm should take
	 * @param bytes      the length of the hash to compute in bytes
	 * @return a hashed algorithm represented in a byte sequence
	 * 
	 */
	private byte[] createPassword(char[] password, byte[] salt, int iterations, int bytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		PBEKeySpec encryptedPassword = new PBEKeySpec(password, salt, iterations, bytes * OUTPUT_SIZE_BYTES);
		SecretKeyFactory secret = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return secret.generateSecret(encryptedPassword).getEncoded();
	}

	/**
	 * <<This method method is not used>> This is an other way of decoding the hash
	 * using base64 number system instead of a hexadecimal number system
	 * 
	 * @return decode the hash using Base64 scheme
	 */
	private static byte[] baseDecode(String hash) {
		return Base64.getDecoder().decode(hash);
	}

	/**
	 * <<This method is not used>> This is another way of encoding the hash using
	 * base64 number system instead of a hexadecimal number system
	 * 
	 * @return encoded hash in a Base64 scheme
	 */
	private static String baseEncode(byte[] hash) {
		return Base64.getEncoder().encodeToString(hash);
	}
}

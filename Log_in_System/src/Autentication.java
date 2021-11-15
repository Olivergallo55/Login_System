import java.awt.GridLayout;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;

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
	 * Generate a hash in a hex string using the password. 
	 * 
	 * @param password is the given password
	 * @return a converted hash and salt represented in a hex string
	 */
	public String generateHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] salt = generateSalt();
		byte[] hash = createPassword(password.toCharArray(), salt, AMOUNT_OF_ITERATIONS, SALT_BYTES);

		return convertHashToString(hash) + ":" + convertHashToString(salt);
	}

	/**
	 * This method converts the password to a byte sequence, by putting 2 hex values 
	 * in one byte in this kind of manner {1,2,3,4} -> {12,34}, which besides the conversion
	 * even saves space. These hex decimals are often represented as 0xC7 to make it more clear 
	 * that it is a hex. The left shifting is equal to *16 and only written as it is to make 
	 * the code more readable.
	 * 
	 * @param password
	 * 
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
	 * This method creates a pbkdf2 hash algorithm to make the password saving more
	 * secure and harder to break. The algorithm hashes the password in a away that
	 * cannot be rehashed and obtained as regular plain text. After the hash have
	 * been created it converts into a string representation.
	 * 
	 * @param password
	 * 
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
	 * @param password is the given password
	 * @param validPassword is the correct password hash
	 * 
	 * @return true if the two hashes are equal and false if they are not
	 * */
	public boolean validateHash(char[] password, String validPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		String[] splitPassword = validPassword.split(":");
		System.out.println(splitPassword.toString());
		byte[] hash = convertHashToByte(splitPassword[0]);
		byte[] salt = convertHashToByte(splitPassword[1]);
		byte[] finalPassword = createPassword(password, salt, AMOUNT_OF_ITERATIONS, hash.length);
		System.out.println("password: " + convertHashToString(finalPassword));

		return slowEquals(hash, finalPassword);

	}

	/**
	 * This method checks if the two passwords given in a byte array are equal.
	 * Through this method the system can eliminate time branch delay that regular
	 * "==" operator gives, due this method a potential attacker wont be able to
	 * estimate a time difference between different passwords.
	 * 
	 * @param a is the password
	 * @param b is the correct hash
	 * 
	 * @return true if the two byte arrays are exactly the same else false
	 */
	private boolean slowEquals(byte[] a, byte[] b) {
		int difference = a.length ^ b.length;
		for (int i = 0; i < a.length && i < b.length; i++) {
			difference |= a[i] ^ b[i];
		}
		return difference == 0 ? true : false;
	}

	/**
	 * Create the pbkfd2 algorithm that hashes the password so it cannot be rehashed
	 * and obtained as a plain text.
	 * 
	 * @param password the password to hash
	 * @param salt the salt
	 * @param iterations the amount of iteration the algorithm should take
	 * @param bytes the length of the hash to compute in bytes
	 * 
	 * @return a hashed algorithm represented in a byte sequence
	 * 
	 */
	private byte[] createPassword(char[] password, byte[] salt, int iterations, int bytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		PBEKeySpec encryptedPassword = new PBEKeySpec(password, salt, iterations, bytes * OUTPUT_SIZE_BYTES);
		SecretKeyFactory secret = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		return secret.generateSecret(encryptedPassword).getEncoded();
	}

//	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
//		Autentication e = new Autentication();
//		
//		JFrame frame = new JFrame();
//		
//		JPanel panel = new JPanel();
//		JTextField a = new JTextField();
//		JTextField b = new JTextField();
//		JButton button = new JButton();
//		panel.setLayout(new GridLayout(4, 2, 4, 4));
//
//		panel.add(a);
//		panel.add(b);
//		panel.add(button);
//		
//		button.addActionListener(x -> {
//			try {
//				String secondPassword = e.generateHash(b.getText());
//				boolean matched = e.validateHash(a.getText().toCharArray(), secondPassword);
//				System.out.println(a.getText() + " " + secondPassword);
//				System.out.println(matched);
//			} catch (NoSuchAlgorithmException | InvalidKeySpecException e1) {
//				e1.printStackTrace();
//			}
//			
//		});
//		
//		frame.add(panel);
//		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//		frame.setSize(300, 300);
//		frame.setVisible(true);
//
//		String originalPassword = "password"; //create password
//
//		String generatedSecuredPasswordHash = null;
//		generatedSecuredPasswordHash = e.generateHash(originalPassword); 
//
//		boolean matched = e.validateHash("password".toCharArray(), generatedSecuredPasswordHash);
//		System.out.println("test with valid password: " + matched);
//
//		matched = e.validateHash("password1".toCharArray(), generatedSecuredPasswordHash);
//		System.out.println("test with invalid password: " + matched);

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
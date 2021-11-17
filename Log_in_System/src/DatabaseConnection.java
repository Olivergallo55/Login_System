import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DatabaseConnection {

	private Connection dbConnection = null;
	private String loginName = "Oliver";
	private String password = "root";
	private String databaseName = "login_database";
	private String serverName = "localhost:3306";
	private String connectorUrl = "jdbc:mysql://" + serverName + "/" + databaseName
			+ "?characterEncoding=latin1&useConfigs=maxPerformance";
	private Autentication au;

	public static void main(String[] args) {
		new DatabaseConnection(new GUI());
	}

	/**
	 * Public constructor
	 **/
	public DatabaseConnection(GUI gui) {
		connectToDatabase();
		au = new Autentication();
	}

	/**
	 * Connects to the database
	 */
	private void connectToDatabase() {
		try {
			Class.forName("com.mysql.jdbc.Driver");
			dbConnection = DriverManager.getConnection(connectorUrl, loginName, password);
		} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Creates new user with user name and password and hashes the password
	 * 
	 * @param username is the input username
	 * @param password is the input password
	 */
	public void createNewUser(String username, String password)
			throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException {
		final PreparedStatement prepareStatement = dbConnection
				.prepareStatement("INSERT INTO usertable(username, password) VALUES(?,?)");
		prepareStatement.setString(1, username);
		String hashedPassword = au.generateHash(password);
		prepareStatement.setString(2, hashedPassword);
		prepareStatement.executeUpdate();

	}

	/**
	 * Method checks if a user exists and then returns either true or false
	 * 
	 * @param username is the user name given by the user
	 * @return true if user name exist and false otherwise
	 */
	public boolean checkUser(String userName) {
		try {
			String user = "SELECT * FROM usertable WHERE username=?";
			final PreparedStatement prepareStatement = dbConnection.prepareStatement(user);
			prepareStatement.setString(1, userName);
			ResultSet set = prepareStatement.executeQuery();

			while (set.next()) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * Method validates the password by getting the user name and the password, hash
	 * it and compare it to the valid hashed password in the database. if the user
	 * name or password is incorrect it will throw an error.
	 * 
	 * @param password is the password given by the user
	 * @param username is the users user name
	 * @return if the password is valid or not
	 */
	public boolean validatePassword(char[] password, String userName) {
		try {
			String user = "SELECT password FROM usertable WHERE username=?";
			final PreparedStatement prepareStatement = dbConnection.prepareStatement(user);
			prepareStatement.setString(1, userName);
			ResultSet set = prepareStatement.executeQuery();

			while (set.next()) {
				String pw = set.getString("password");
				boolean match = au.validateHash(password, pw);
				if (match)
					return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * Deletes a user from the database
	 * 
	 * @param usernname is the users user name
	 **/
	public void deleteUser(String userName) {
		try {
			final PreparedStatement prepareStatement = dbConnection
					.prepareStatement("DELETE FROM usertable WHERE username=?");
			prepareStatement.setString(1, userName);
			prepareStatement.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method updates the users password
	 * 
	 * @param password is the new password
	 * @param userName is the users user name who's password is going to be updated
	 **/
	public void updatePassword(String password, String userName) {
		try {
			final PreparedStatement prepareStatement = dbConnection
					.prepareStatement("UPDATE usertable SET password=? WHERE username=?");
			String hashedPassword = au.generateHash(password);
			prepareStatement.setString(1, hashedPassword);
			prepareStatement.setString(2, userName);
			prepareStatement.executeUpdate();
		} catch (SQLException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
}

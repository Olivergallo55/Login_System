import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseConnection {

	private Connection dbConnection = null;
	// private Statement statement = null;
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

	public DatabaseConnection(GUI gui) {
		connectToDatabase();
		au = new Autentication();
	}

	private void connectToDatabase() {
		try {
			Class.forName("com.mysql.jdbc.Driver");
			dbConnection = DriverManager.getConnection(connectorUrl, loginName, password);
			// Statement statement = dbConnection.createStatement();
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

	// method check if the username already exists
	public boolean checkUser(String userName) {
		try {
			String user = "SELECT * FROM usertable WHERE username=?";
			final PreparedStatement prepareStatement = dbConnection.prepareStatement(user);
			prepareStatement.setString(1, userName);
			ResultSet set = prepareStatement.executeQuery();

			while (set.next()) {
				System.out.println("User Exist!");
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	// validate password
	// TODO put in finally block
	public boolean validatePassword(char[] password, String userName) {
		PreparedStatement prepareStatement = null;

		try {
			String user = "SELECT password FROM usertable WHERE username=?";
			prepareStatement = dbConnection.prepareStatement(user);
			prepareStatement.setString(1, userName);
			ResultSet set = prepareStatement.executeQuery();

			while (set.next()) {
				String pw = set.getString("password");
				System.out.println("db password: " + pw);
				boolean match = au.validateHash(password, pw);
				if (match)
					return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

}

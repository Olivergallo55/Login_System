import java.awt.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import javax.swing.*;
import java.util.ArrayList;

public class GUI {

	private ArrayList<JPanel> panels = new ArrayList<JPanel>();
	private JButton loginButton;
	private JButton logoutButton;
	private JButton createUserButton;
	// private JButton changePasswordButton;
	public JTextField usernameField;
	public JTextField userField;
	private JPasswordField password;
	public JPasswordField passwordField;
	private JPanel panel = null;
	private JFrame frame;
	private int height = 300, weidth = 200;
	int count = 0;
	private DatabaseConnection db;
	private Autentication au;

	public GUI() {
		createGUI();
	}

	private void initalizeVariables() {
		frame = new JFrame();
		loginButton = new JButton("Log in");
		logoutButton = new JButton("Log out");
		createUserButton = new JButton("Create new User");
		db = new DatabaseConnection(this);
		au = new Autentication();
		usernameField = new JTextField();
		passwordField = new JPasswordField();
		passwordField.setEchoChar('*');
		userField = new JTextField();
		password = new JPasswordField();
	}

	private void createGUI() {
		initalizeVariables();
		panel = createPanel1();
		buttonHandlers();
		frame.setTitle("Login Application");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setSize(height, weidth);
		frame.setVisible(true);
	}

	private void buttonHandlers() {
		loginButtonHandler();
		logoutButtonHandler();
		createNewUserButtonHandler();
	}

	private void createNewUserButtonHandler() {
		createUserButton.addActionListener(e -> {

			createNewUserWindow();

			if (!userField.getText().isBlank() && password.getPassword().length != 0) {
				try {
					db.createNewUser(userField.getText(), String.valueOf(password.getPassword()));
				} catch (SQLException | NoSuchAlgorithmException | InvalidKeySpecException e1) {
					userField.setText("");
					password.setText("");
					JOptionPane.showMessageDialog(null, "User already exist");
				}
			} else {
				JOptionPane.showMessageDialog(null, "Username or password field is empty");
			}
		});
	}

	private void logoutButtonHandler() {

		logoutButton.addActionListener(e -> {
			changeToWindow1();

		});
	}
	

	private void loginButtonHandler() {

		loginButton.addActionListener(e -> {

			if (db.validatePassword(password.getPassword(), usernameField.getText())) {
//				try {
//					if (!usernameField.getText().isEmpty() && passwordField.getPassword().length != 0) {
//						String pass = au.generateHash(passwordField.getPassword());
//						db.createNewUser(usernameField.getText(), pass);
//					} else
//						JOptionPane.showMessageDialog(null, "Username or password cannot be empty");
//
//				} catch (SQLException | InvalidKeySpecException | NoSuchAlgorithmException x) {
//					x.printStackTrace();
//					JOptionPane.showMessageDialog(null, "User already exist");
//				}

				// db.checkUser(usernameField.getText());
				changeToWindow2();
			}else {
				JOptionPane.showMessageDialog(null, "Wrong username or password");
			}
		});
	}

	private void changeToWindow1() {
		clearWindow();
		panel = createPanel1();
		repaintWindow();
		panel.setVisible(true);
		usernameField.setText("");
		passwordField.setText("");
	}

	private void changeToWindow2() {
		clearWindow();
		panel = createPanel2();
		repaintWindow();
		panel.setVisible(true);
	}

	private JPanel createPanel1() {
		JPanel panel1 = new JPanel();
		panel1.setLayout(new GridLayout(4, 2, 4, 4));
		panel1.add(new JLabel("User name"));
		panel1.add(new JLabel("Password"));
		panel1.add(usernameField);
		panel1.add(passwordField);
		panel1.add(loginButton);
		panel1.add(createUserButton);
		JButton showPasswordButton = new JButton("Show Password");
		showPasswordButton.setBounds(300, 300, 50, 50);
		showPasswordButton.addActionListener(e -> {
			showPassword();
		});
		panel1.add(showPasswordButton);
		frame.add(panel1, BorderLayout.NORTH);
		panels.add(panel1);
		return panel1;
	}

	private JPanel createPanel2() {
		JPanel panel2 = new JPanel();
		panel2.add(new JLabel("Panel2"));
		panel2.add(logoutButton);
		frame.add(panel2, BorderLayout.NORTH);
		panels.add(panel2);
		return panel2;
	}

	private void createNewUserWindow() {
		JPanel main = new JPanel(new BorderLayout(5, 5));

		JPanel labels = new JPanel(new GridLayout(0, 1, 2, 2));
		labels.add(new JLabel("Username", SwingConstants.TRAILING));
		labels.add(new JLabel("Password", SwingConstants.TRAILING));
		main.add(labels, BorderLayout.LINE_START);

		JPanel textFields = new JPanel(new GridLayout(0, 1, 2, 2));
		textFields.add(userField);
		textFields.add(password);
		main.add(textFields, BorderLayout.CENTER);

		UIManager.put("OptionPane.minimumSize", new Dimension(350, 80));
		JOptionPane.showMessageDialog(frame, main, "Create a new user", JOptionPane.QUESTION_MESSAGE);
	}

	private boolean isEven(int count) {
		return count % 2 == 0 ? true : false;
	}

	private void showPassword() {
		if (isEven(count)) {
			passwordField.setEchoChar((char) 0);
			count++;
		} else {
			passwordField.setEchoChar('*');
			count++;
		}
	}

	// TODO use
	private boolean checkEmptyField() {
		return true;
	}

	private void clearWindow() {
		for (JPanel c : panels)
			frame.getContentPane().remove(c);
	}

	private void repaintWindow() {
		frame.getContentPane().revalidate();
		frame.getContentPane().repaint();
	}

	// TODO use regex to make a good password

}


public class UserDao {
    public void getUser(String id) {
        String query = "SELECT * FROM users WHERE id = " + id;
        statement.execute(query);
    }
}

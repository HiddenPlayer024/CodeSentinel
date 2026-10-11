
public class UserDaoSafe {
    public void getUser(String id) {
        String query = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = connection.prepareStatement(query);
        pstmt.setString(1, id);
        pstmt.execute();
    }
}

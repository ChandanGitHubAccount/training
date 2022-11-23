package zomatomodified.zomato.coustomexcptions;

public class LoginFailedException extends Exception {
    public LoginFailedException(String message) {
        super(message);
    }
}

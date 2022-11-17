package zomato.coustomexcptions;

public class SessionIdExpiredException extends Exception {
    public SessionIdExpiredException(String message) {
        super(message);
    }
}

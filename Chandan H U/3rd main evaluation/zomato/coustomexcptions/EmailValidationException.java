package zomato.coustomexcptions;

public class EmailValidationException extends Exception{
    public EmailValidationException(String message) {
        super(message);
    }
}

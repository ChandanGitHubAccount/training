package zomato.advice;

import org.hibernate.id.IdentifierGenerationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import zomato.coustomexcptions.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.sql.SQLSyntaxErrorException;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handelMethodArgumentNotValidException(MethodArgumentNotValidException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        exception.getBindingResult().getFieldErrors().forEach(errors -> errorMessage.put(errors.getField(), errors.getDefaultMessage()));
        return errorMessage;
    }

    @ExceptionHandler(NullPointerException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelNullPointerException(NullPointerException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelMissingServletRequestPartException(MissingServletRequestPartException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(BindException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelBindException(BindException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(FileNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelFileNotFoundException(FileNotFoundException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(IndexOutOfBoundsException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelIndexOutOfBoundsException(IndexOutOfBoundsException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(SQLIntegrityConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleSQLIntegrityConstraintViolationException(SQLIntegrityConstraintViolationException exception) {
        Map<String, String> stringStringMap = new HashMap<>();
        stringStringMap.put("error message", exception.getMessage());
        return stringStringMap;
    }

    @ExceptionHandler(DuplicateKeyException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleDuplicateKeyException(DuplicateKeyException exception) {
        Map<String, String> stringStringMap = new HashMap<>();
        stringStringMap.put("error message", "Already present in your list list");
        return stringStringMap;
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.GATEWAY_TIMEOUT)
    public Map<String, String> handelHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelMissingServletRequestParameterException(MissingServletRequestParameterException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(IOException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelIOException(IOException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(IdentifierGenerationException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelIdentifierGenerationException(IdentifierGenerationException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage() + "\nplease select the photo proper image");
        return errorMessage;
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelAccessDeniedException(AccessDeniedException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", "please select the photo proper image");
        return errorMessage;
    }

    @ExceptionHandler(IllegalStateException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelIllegalStateException(IllegalStateException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", "please select the photo proper image");
        return errorMessage;
    }

    @ExceptionHandler(SQLSyntaxErrorException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleSQLSyntaxErrorException(SQLSyntaxErrorException exception) {
        Map<String, String> stringStringMap = new HashMap<>();
        stringStringMap.put("error message", exception.getMessage());
        return stringStringMap;
    }

    @ExceptionHandler(LoginFailedException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelLoginFailedException(LoginFailedException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(SignupException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handelSignupException(SignupException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(SignOutException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handelSignOutException(SignOutException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(SessionIdExpiredException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handelSessionIdExpiredException(SessionIdExpiredException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelUsernameNotFoundException(UsernameNotFoundException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(TokenExpiredException.class)
    @ResponseStatus(HttpStatus.GATEWAY_TIMEOUT)
    public Map<String, String> handelTokenExpiredException(TokenExpiredException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(EmailValidationException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelEmailValidationException(EmailValidationException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(OTPGenerateException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelOTPGenerateException(OTPGenerateException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(InvalidTimeException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelInvalidTimeException(InvalidTimeException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(UpdateFailedException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelUpdateFailedException(UpdateFailedException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }

    @ExceptionHandler(InvalidCardNumberException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Map<String, String> handelInvalidCardNumberException(InvalidCardNumberException exception) {
        Map<String, String> errorMessage = new HashMap<>();
        errorMessage.put("Error message ", exception.getMessage());
        return errorMessage;
    }
}

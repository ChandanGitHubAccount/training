package September26;

public class User {
    String bookNumber;
    public User(String bookNumber) {
        this.bookNumber = bookNumber;
    }

    public String to_String(){
        return "\nBook number : " + bookNumber;
    }
}

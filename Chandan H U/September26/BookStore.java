package September26;

public class BookStore {
    String bookAuthor, bookName;
    double bookPrice;
    long bookStocks;

    BookStore(String bookName , String bookAuthor, double bookPrice, long bookStocks) {
        this.bookAuthor = bookAuthor;
        this.bookName = bookName;
        this.bookPrice = bookPrice;
        this.bookStocks = bookStocks;
    }

   public String to_String(){
        return("bookName : " + bookName + "\nbookAuthor : " + bookAuthor + "\nbookPrice : " + bookPrice + "\nbookStocks : " + bookStocks);
    }
}

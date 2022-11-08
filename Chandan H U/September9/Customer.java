package September9;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

class BookStore {
    String bookName, bookNumber, bookAuthor;
    double bookPrice;
    long bookStocks;

    BookStore(String bookName, String bookNumber, String bookAuthor, double bookPrice, long bookStocks) {
        this.bookAuthor = bookAuthor;
        this.bookName = bookName;
        this.bookNumber = bookNumber;
        this.bookPrice = bookPrice;
        this.bookStocks = bookStocks;
    }

}

public class Customer {
    static Map<String, BookStore> books = new HashMap<>();
    static Scanner scan = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("enter the maximun number of book that can placed in store");
        int maximunBooksInStore = scan.nextInt();
        boolean bool=true;

        BookStore book[] = new BookStore[maximunBooksInStore];
        System.out.println("enter 1:administator\n2:coustmer");
        switch (scan.nextInt()) {
            case 1 -> addBooksTOStore(book);
            case 2 -> {
                while (bool) {
                    System.out.println("""
                            enter
                            1:search for book information weather it is avilable or not and get details about it.
                            2:to get information about the books avilable in store.
                            3:to checks stocks.
                            4:to buy book
                            5:to exit""");
                    int choose = scan.nextInt();
                    System.out.println("enter the book name");
                    String bookName = scan.next();
                    switch (choose) {
                        case 1 -> informationAboutBooks(bookName);

                        case 2 -> {
                            if (searchForBook(bookName))
                                System.out.println(bookName + " : is avilable in store");
                            else
                                System.out.println(bookName + "is not avilable in store");
                        }
                        case 3 -> checkForBookStoks(bookName);
                        case 4 -> buyBookInStore(bookName);
                        case 5 -> bool = false;
                    }
                }
            }
        }
    }

    private static void addBooksTOStore(BookStore book[]) {

        int choice, count = 0;
        do {
            System.out.println("enter the book name");
            String bookName = scan.next();
            System.out.println("enter the book number");
            String bookNumber = scan.next();
            System.out.println("enter the author of book");
            String bookAuthor = scan.next();
            System.out.println("enter the book price");
            double bookPrice = scan.nextDouble();
            System.out.println("enter the number of books in stock");
            long bookStocks = scan.nextLong();
            //constructor
            book[count] = new BookStore(bookName, bookNumber, bookAuthor, bookPrice, bookStocks);
            //key-value pairs
            books.put(bookName, book[count]);
            count++;
            System.out.println("enter 1 to add more books or 0 to stop");
            choice = scan.nextInt();
        } while (choice == 1);
    }

    private static void buyBookInStore(String bookName) {
        if (books.containsKey(bookName) && books.get(bookName).bookStocks > 0
        )
            checkPriceOfBook(bookName, books);
        else
            System.out.println(bookName + "is not avilable in store");
    }

    private static void checkPriceOfBook(String bookName, Map<String, BookStore> books) {
        System.out.println("the price of book : " + books.get(bookName).bookPrice);
        System.out.println("enter 1 to buy book else 0");
        int choice = scan.nextInt();
        if (choice == 1) {
            System.out.println("enter how many book u want to buy");
            long numberOfBooksBuying = scan.nextLong();
            if (!checkForStockAvilability(bookName, numberOfBooksBuying)) {
                System.out.println("Books out of Stock");
                return;
            }
            updateBooksInStore(bookName, numberOfBooksBuying);

            payingBillFprBooks(numberOfBooksBuying, bookName);
        } else
            System.out.println("I cannot offer the book");
    }

    private static void payingBillFprBooks(long numberOfBooksBuying, String bookName) {
        System.out.println("The bill paid for books : " + books.get(bookName).bookPrice * numberOfBooksBuying);
    }

    private static boolean checkForStockAvilability(String bookName, long numberOfBooksBuying) {
        return books.get(bookName).bookStocks > numberOfBooksBuying;
    }

    private static void updateBooksInStore(String bookName, long numberOfBooksBuying) {
        if (books.get(bookName).bookStocks > 0)
            books.get(bookName).bookStocks -= numberOfBooksBuying;
    }

    private static boolean searchForBook(String bookName) {
        return books.containsKey(bookName);
    }

    private static void checkForBookStoks(String bookName) {
        if (books.containsKey(bookName))
            System.out.println("the total books avilable in store:" + books.get(bookName).bookStocks);
        else
            System.out.println(bookName + "is not avilable in store");

    }

    private static void informationAboutBooks(String bookName) {
        if (books.containsKey(bookName))
            System.out.println("Bookname: " + books.get(bookName).bookName + "\n" + "Book author: " + books.get(bookName).bookAuthor + "\nBook number: " +
                    books.get(bookName).bookNumber + "\nBook price :" + books.get(bookName).bookPrice + "\nBook stocks :" + books.get(bookName).bookStocks);
        else
            System.out.println(bookName + "is not avilable in store");
    }
}
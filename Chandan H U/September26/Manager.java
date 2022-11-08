package September26;

import org.springframework.context.support.ClassPathXmlApplicationContext;

public class Manager {
    public static void main(String[] args) {

        ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");
        //BookStore class
        System.out.println("xml using constructor\n");

       BookStore  bookStore = (BookStore) context.getBean("bookstore_1");
       //BookStore  bookStore = context.getBean("bookstore_1",BookStore.class); # is same as above.
       System.out.println(bookStore.to_String());

       //User class
       User user = (User) context.getBean("user_1");
       System.out.println(user.to_String());

        //BookStoreMap Class
        BookStoreMap storeMap = (BookStoreMap) context.getBean("bookstore-map_1");
        storeMap.display();
        System.out.println();

        //by using setter methods
        //ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");

        System.out.println("xml using getter and setter methods\n");
        //Books class
        Books books = (Books) context.getBean("books_2");
        System.out.println(("bookName : " + books.getBookName() + "\nbookAuthor : " + books.getBookAuthor() + "\nbookPrice : " + books.getBookPrice()));

        //User class
        Users users = (Users) context.getBean("user_2");
        System.out.println("\nbookNumber : " + users.getBookNumber());

        //BooksStoreUsingGetter class
        BooksStoreUsingGetter booksStoreUsingGetter = (BooksStoreUsingGetter) context.getBean("books_by_setter");

        for(Users key : booksStoreUsingGetter.getBooksMap().keySet())
            System.out.println("\nBook details are : " + "\nBook number : " + key.getBookNumber() + "\n1).Book name : " +
                    booksStoreUsingGetter.getBooksMap().get(key).getBookName() + "\n2).Book author : " +
                    booksStoreUsingGetter.getBooksMap().get(key).getBookAuthor() + "\n3).Book price : " +
                    booksStoreUsingGetter.getBooksMap().get(key).getBookPrice());
    }
}

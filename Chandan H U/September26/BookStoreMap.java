package September26;

import java.util.Map;

public class BookStoreMap {

    Map<User,BookStore> storeMap ;


    BookStoreMap(Map<User, BookStore> storeMap){
        super();
        this.storeMap = storeMap ;
    }


    public void display(){
        for(User key:storeMap.keySet())
            System.out.println("\nBook details are : " + "\nBook number : " + key.bookNumber + "\n1).Book name : " + storeMap.get(key).bookName +
                    "\n2).Book author : " + storeMap.get(key).bookAuthor + "\n3).Book price : " + storeMap.get(key).bookPrice +
                    "\n4).Book stocks : " + storeMap.get(key).bookStocks);
    }
}

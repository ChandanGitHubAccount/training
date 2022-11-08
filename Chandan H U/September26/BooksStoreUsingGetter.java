package September26;

import java.util.Map;

public class BooksStoreUsingGetter {
    private Map<Users , Books> booksMap ;

    public Map<Users, Books> getBooksMap() {return booksMap;}

    public void setBooksMap(Map<Users, Books> booksMap) {this.booksMap = booksMap;}

}

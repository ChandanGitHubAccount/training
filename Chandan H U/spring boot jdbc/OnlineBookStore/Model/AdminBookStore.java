package example.OnlineBookStore.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AdminBookStore {
    private String bookNumber;
    private String bookName;
    private int numberOfBooks;
    private int bookPrice;
}

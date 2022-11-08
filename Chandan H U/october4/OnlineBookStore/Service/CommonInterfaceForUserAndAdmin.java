package example.OnlineBookStore.Service;

import example.OnlineBookStore.Model.AdminBookStore;

import java.util.List;

public interface CommonInterfaceForUserAndAdmin {
    List<AdminBookStore> viewAvailableBooksInStore();
}

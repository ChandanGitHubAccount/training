package zomatomodified.zomato.service.user;

import zomatomodified.zomato.coustomexcptions.InvalidCardNumberException;
import zomatomodified.zomato.entity.Users;

public interface RoleInterface {
    String changeRole(String gstNumber) throws InvalidCardNumberException;

    String editUser(Users users);
}

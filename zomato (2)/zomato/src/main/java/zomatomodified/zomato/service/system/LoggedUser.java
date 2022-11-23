package zomatomodified.zomato.service.system;

import org.springframework.stereotype.Component;
import zomatomodified.zomato.entity.Users;

@Component
public class LoggedUser {
    private Users users;

    public void setLoggedUser(Users user) {
        this.users = user;
    }

    public Users getUsers() {
        return this.users;
    }

}


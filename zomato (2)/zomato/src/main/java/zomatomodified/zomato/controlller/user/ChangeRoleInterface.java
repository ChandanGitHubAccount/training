package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.coustomexcptions.InvalidCardNumberException;
import zomatomodified.zomato.entity.Users;
import zomatomodified.zomato.service.user.RoleInterface;

import java.util.Optional;

@RestController
@RequestMapping("/user")
public class ChangeRoleInterface {

    @Autowired
    private RoleInterface roleInterface;

    @PatchMapping("/change-role")
    public ResponseEntity<String> changeRole(@RequestHeader String gstNumber) throws InvalidCardNumberException {
        return ResponseEntity.of(Optional.of(roleInterface.changeRole(gstNumber)));
    }

    @PutMapping("/edit-user")
    public ResponseEntity<String> edit(@ModelAttribute Users user){
        return ResponseEntity.of(Optional.of(roleInterface.editUser(user)));
    }

}

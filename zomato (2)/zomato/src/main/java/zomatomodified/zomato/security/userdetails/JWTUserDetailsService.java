package zomatomodified.zomato.security.userdetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import zomatomodified.zomato.entity.Users;
import zomatomodified.zomato.repository.UserRepository;

import java.util.ArrayList;
import java.util.List;

@Service
public class JWTUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        List<Users> user = userRepository.findByEmail(email);
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(user.get(0).getRole()));
        if (user.isEmpty())
            throw new UsernameNotFoundException("Account not found");
        return new User(email, user.get(0).getPassword(), authorities);
    }

}

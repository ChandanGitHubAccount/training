package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Person;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class PersonService implements PersonServiceInterface {
    @Autowired
    JdbcTemplate jdbcTemplate;
    @Override
    public Person addPerson(Person person) {
        try{
            jdbcTemplate.update("INSERT INTO person VALUES (? , ? ,?)",person.getId(),person.getName(),person.getAddress());
            return person;
        }catch (Exception exception){
            System.out.println("Record not found." + exception);
            return null;
        }
    }

    @Override
    public List<Person> removePerson(String personId) {
        try{
            List<Person> personList = jdbcTemplate.query("SELECT * FROM person WHERE  id= ?" , new BeanPropertyRowMapper<>(Person.class) , personId);
        jdbcTemplate.update("DELETE FROM person WHERE id = ?" , personId);
        return personList;
        }catch (Exception exception){
            System.out.println("Not found." + exception);
            return null;
        }
    }

    @Override
    public List<Person> viewAllPersonDetails() {
        try{
            return jdbcTemplate.query("SELECT * FROM person" , new BeanPropertyRowMapper<>(Person.class));
        }catch (Exception exception){
            System.out.println("Not found." + exception);
            return null;
        }
    }
}

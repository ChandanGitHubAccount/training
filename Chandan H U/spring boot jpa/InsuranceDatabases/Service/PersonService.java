package InsuranceDatabases.Service;

import InsuranceDatabases.Model.Person;
import InsuranceDatabases.Repository.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PersonService implements PersonServiceInterface {

    @Autowired
    private PersonRepository personRepository;

    @Override
    public Person addPerson(Person person) {
        try {
            return personRepository.save(person);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<Person> getAllPerson() {
        try {
            return personRepository.findAll();
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public Optional<Person> getParticularPersonDetails(int driverId) {
        try {
            return personRepository.findById(driverId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return Optional.empty();
        }
    }
}

package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Person;

import java.util.List;

public interface PersonServiceInterface {
    Person addPerson(Person person);
    List<Person> removePerson(String personId);
    List<Person> viewAllPersonDetails();
}

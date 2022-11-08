package InsuranceDatabases.Service;

import InsuranceDatabases.Model.*;
import InsuranceDatabases.Repository.ParticipatedRepository;
import InsuranceDatabases.Repository.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ParticipatedService implements ParticipatedServiceInterface {

    @Autowired
    private ParticipatedRepository participatedRepository;
    @Autowired
    private PersonRepository personRepository;

    @Override
    public Participated addParticipated(Participated participated) {
        try {
            return participatedRepository.save(participated);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<Participated> getAllParticipated() {
        try {
            return participatedRepository.findAll();
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public Optional<Participated> getParticularParticipatedDetails(ParticipatedPk participatedPk) {
        try {
            return participatedRepository.findById(participatedPk);
        } catch (Exception exception) {
            exception.printStackTrace();
            return Optional.empty();
        }
    }

    //1.Find the total number of people who owned cars that were involved in accidents in 1989.
    @Override
    public long getNumberOfPeopleMadeAccidentInParticularYear(int year) {
        try {
            return participatedRepository.findNumberOfPeopleMadeAccidentInParticularYear(year);
        } catch (Exception exception) {
            exception.printStackTrace();
            return 0L;
        }
    }

    //2. Find the number of accidents in which the cars belonging to “Rahul” were involved.
    @Override
    public long numberOfAccidentMadeByParticularPerson(String personName) {
        try {
            List<Person> personList = personRepository.findByPersonName(personName);
            Person person = personList.get(0);
            return participatedRepository.countByPerson(person);
        } catch (Exception exception) {
            exception.printStackTrace();
            return 0L;
        }
    }

    //3.Update the damage amount for the car with reg number “2” in the accident with report number “1” to 3000.
    @Override
    public int updateDamageAmounts(int damageAmount, int carRgeNo, int accidentReportNo) {
        try {
            participatedRepository.damageAmountUpdate(damageAmount, carRgeNo, accidentReportNo);

            return damageAmount;
        } catch (Exception exception) {
            exception.printStackTrace();
            return 0;
        }
    }
}

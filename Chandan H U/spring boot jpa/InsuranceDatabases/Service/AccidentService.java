package InsuranceDatabases.Service;

import InsuranceDatabases.Model.Accident;
import InsuranceDatabases.Repository.AccidentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AccidentService implements AccidentServiceInterface {

    @Autowired
    private AccidentRepository accidentRepository;

    @Override
    public Accident addAccidents(Accident accident) {
        try {
            return accidentRepository.save(accident);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<Accident> getAllAccident() {
        try {
            return accidentRepository.findAll();
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public Optional<Accident> getParticularAccidentDetails(int accidentId) {
        try {
            return accidentRepository.findById(accidentId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return Optional.empty();
        }
    }
}

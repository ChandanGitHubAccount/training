package InsuranceDatabases.Service;

import InsuranceDatabases.Model.Accident;

import java.util.List;
import java.util.Optional;

public interface AccidentServiceInterface {
    Accident addAccidents(Accident accident);

    List<Accident> getAllAccident();

    Optional<Accident> getParticularAccidentDetails(int accidentId);

}

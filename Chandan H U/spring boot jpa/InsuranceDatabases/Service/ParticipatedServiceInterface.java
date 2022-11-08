package InsuranceDatabases.Service;

import InsuranceDatabases.Model.Participated;
import InsuranceDatabases.Model.ParticipatedPk;

import java.util.List;
import java.util.Optional;

public interface ParticipatedServiceInterface {
    Participated addParticipated(Participated participated);

    List<Participated> getAllParticipated();

    Optional<Participated> getParticularParticipatedDetails(ParticipatedPk participatedPk);

    long getNumberOfPeopleMadeAccidentInParticularYear(int year);

    long numberOfAccidentMadeByParticularPerson(String personName);

    int updateDamageAmounts(int damageAmount, int carRgeNo, int accidentReportNo);
}

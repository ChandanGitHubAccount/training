package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Accident;

import java.util.List;

public interface AccidentServiceInterface {
    Accident addAccidents(Accident accident);
    List<Accident> removeAccidents(int accidentReportNo);
    List<Accident> showAllAccidentDetails();

}

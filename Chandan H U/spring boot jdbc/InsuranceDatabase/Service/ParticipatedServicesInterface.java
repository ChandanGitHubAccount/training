package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Participated;

import java.util.List;

public interface ParticipatedServicesInterface {
    Integer totalNumberOfAccidentHappenInGivenYear(int year);
    Integer numberAccidentMadeByParticularPerson(String personName);
    List<Participated> viewAllParticipatedDetails();
    Integer updateParticipatedDamageAmount(String carRegNo , int accidentReportNo , Integer amount);
}

package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.CarOwner;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public interface CarOwnerServiceInterface {
    List<CarOwner> viewCarOwnerDetails();
}

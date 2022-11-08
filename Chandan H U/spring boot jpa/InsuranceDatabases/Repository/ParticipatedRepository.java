package InsuranceDatabases.Repository;

import InsuranceDatabases.Model.Participated;
import InsuranceDatabases.Model.ParticipatedPk;
import InsuranceDatabases.Model.Person;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface ParticipatedRepository extends JpaRepository<Participated, ParticipatedPk> {

    @Modifying
    @Transactional
    @Query(value = "update participated set damage_amount = :damage_amount where accident_report_no = :accident_report_no and car_reg_no= :car_reg_no", nativeQuery = true)
    void damageAmountUpdate(@Param("damage_amount") int damage_amount, @Param("accident_report_no") int accident_report_no, @Param("car_reg_no") int car_reg_no);

    long countByPerson(Person person);

    @Query(value = "select count(driver_id) as number_of_people from participated where accident_report_no in(select accident_report_no from accident where year(accident_date)= :year)", nativeQuery = true)
    long findNumberOfPeopleMadeAccidentInParticularYear(@Param("year") int year);

}

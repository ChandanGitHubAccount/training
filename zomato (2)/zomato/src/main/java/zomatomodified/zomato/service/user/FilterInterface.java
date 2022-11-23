package zomatomodified.zomato.service.user;

import zomatomodified.zomato.model.FilterModel;
import zomatomodified.zomato.model.Restaurants;

import java.util.List;

public interface FilterInterface {

    List<String> viewSortOptions();

    List<String> otherFilters();

    List<Restaurants> filterAll(FilterModel filterModel, int pageSize, int pageNumber);

    List<String> showPaymentType();
}

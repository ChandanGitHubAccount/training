package zomato.service.user;

import zomato.coustomexcptions.SessionIdExpiredException;

import java.util.List;

public interface SearchInterface {
    List<?> search(String field) throws SessionIdExpiredException;
}

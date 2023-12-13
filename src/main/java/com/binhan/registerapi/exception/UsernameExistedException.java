package com.binhan.registerapi.exception;

public class UsernameExistedException extends RuntimeException{
    public UsernameExistedException(String err){
        super(err);
    }
}

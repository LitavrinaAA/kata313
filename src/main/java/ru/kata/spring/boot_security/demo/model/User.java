package ru.kata.spring.boot_security.demo.model;



import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;
import java.util.Collection;
import java.util.HashSet;

@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private long id;
    @Column(name = "name")
    @NotEmpty(message = "Name should not be empty")
    @Size( min = 2, max = 30, message = "Имя от 2 до 30 символов")
    private String name;
    @Column(name = "surname")
    @NotEmpty(message = "Name should not be empty")
    @Size( min = 2, max = 30, message = "Фамилия от 2 до 30 символов")
    private String surname;
    @Column(name = "salary")
    @Min( value = 100, message = "Ой...это что ж за работа? тебе не стыдно? ")
    @Max( value = 1000000, message = "Нет, тут столько зарабатывать не зарзрешают...Скромнее, пожалуйста")
    private int salary;

    @NotEmpty(message = "Username should not be empty")
    private String username;
    @NotEmpty(message = "Pass should not be empty")
    private String password;

    @ManyToMany(fetch = FetchType.LAZY)
    @LazyCollection(LazyCollectionOption.EXTRA)
    @Fetch(FetchMode.JOIN)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Collection<Role> roles;


    public User() {
    }

    public User(long id, String name, String surname, int salary, String username, String password, Collection<Role> roles) {
        this.id = id;
        this.name = name;
        this.surname = surname;
        this.salary = salary;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    public long getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public int getSalary() {
        return salary;
    }

    public void setSalary(int salary) {
        this.salary = salary;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Collection<Role> getRoles() {
        return roles;
    }

    public void setRoles(Collection<Role> roles) {
        this.roles = roles;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", surname='" + surname + '\'' +
                ", salary=" + salary +
                '}';
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }



    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
    public void addRole(Role role) {
        if (this.roles == null) {
            this.roles = new HashSet<>();
        }
        this.roles.add(role);
    }
}

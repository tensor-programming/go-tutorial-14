package main

import (
	"html/template"
	"io"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"

	"github.com/asaskevich/govalidator"
	"github.com/gorilla/securecookie"
	"strings"
)

var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func view(w http.ResponseWriter, r *http.Request) {
	uuid := getUuid(r)
	if uuid != "" {
		title := r.URL.Path[len("/test/"):]
		p, err := loadSource(title)
		if err != nil {
			p, _ = load(title)
		}
		if p.Title == "" {
			p, _ = load(title)
		}

		render(w, "test", p)
		return
	}
	http.Redirect(w, r, "/", 302)
	return

}

func edit(w http.ResponseWriter, r *http.Request) {
	uuid := getUuid(r)
	if uuid != "" {
		title := r.URL.Path[len("/edit/"):]
		p, err := loadSource(title)
		if err != nil {
			p, _ = load(title)
		}
		if p.Title == "" {
			p, _ = load(title)
		}

		render(w, "edit", p)
		return
	}
	http.Redirect(w, r, "/", 302)
	return
}

func save(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Path[len("/save/"):]

	body := r.FormValue("body")
	p := &Page{Title: title, Body: []byte(body)}
	p.saveCache()
	http.Redirect(w, r, "/test/"+title, http.StatusFound)
}

func upload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		uuid := getUuid(r)
		if uuid != "" {
			title := "Upload"
			p := &Page{Title: title}
			render(w, "upload", p)
			return
		}
		http.Redirect(w, r, "/", 302)
		return

	case "POST":
		err := r.ParseMultipartForm(100000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		m := r.MultipartForm
		files := m.File["myfiles"]
		for i := range files {
			file, err := files[i].Open()
			defer file.Close()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			f, err := os.Create("./files/" + files[i].Filename)
			defer f.Close()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, err := io.Copy(f, file); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/files/"+files[i].Filename, http.StatusFound)

		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func indexPage(w http.ResponseWriter, r *http.Request) {
	uuid := getUuid(r)
	if uuid != "" {
		http.Redirect(w, r, "/example", 302)
		return
	}
	msg := getMsg(w, r, "message")
	var u = &User{}
	u.Errors = make(map[string]string)
	if msg != "" {
		u.Errors["message"] = msg
		render(w, "signin", u)
	} else {
		u := &User{}
		render(w, "signin", u)
	}

}

func login(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("uname")
	pass := r.FormValue("password")
	u := &User{Username: name, Password: pass}
	redirect := "/"
	if name != "" && pass != "" {
		if b, uuid := userExists(u); b == true {
			setSession(&User{Uuid: uuid}, w)
			redirect = "/example"
		} else {
			setMsg(w, "message", "please signup or enter a valid username and password!")
		}
	} else {
		setMsg(w, "message", "Username or Password field are empty!")
	}
	http.Redirect(w, r, redirect, 302)
}

func logout(w http.ResponseWriter, r *http.Request) {
	clearSession(w, "session")
	http.Redirect(w, r, "/", 302)
}

func examplePage(w http.ResponseWriter, r *http.Request) {
	uuid := getUuid(r)
	u := getUserFromUuid(uuid)
	if uuid != "" {
		render(w, "internal", u)
	} else {
		setMsg(w, "message", "Please login first!")
		http.Redirect(w, r, "/", 302)
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		u := &User{}
		u.Errors = make(map[string]string)
		u.Errors["lname"] = getMsg(w, r, "lname")
		u.Errors["fname"] = getMsg(w, r, "fname")
		u.Errors["email"] = getMsg(w, r, "email")
		u.Errors["username"] = getMsg(w, r, "username")
		u.Errors["password"] = getMsg(w, r, "password")
		render(w, "signup", u)
	case "POST":
		if n := checkUser(r.FormValue("userName")); n == true {
			setMsg(w, "username", "User already exists. Please enter a unique username!")
			http.Redirect(w, r, "/signup", 302)
			return
		}
		u := &User{
			Uuid:     Uuid(),
			Fname:    r.FormValue("fName"),
			Lname:    r.FormValue("lName"),
			Email:    r.FormValue("email"),
			Username: r.FormValue("userName"),
			Password: r.FormValue("password"),
		}
		result, err := govalidator.ValidateStruct(u)
		if err != nil {
			e := err.Error()
			if re := strings.Contains(e, "Lname"); re == true {
				setMsg(w, "lname", "Please enter a valid Last Name")
			}
			if re := strings.Contains(e, "Email"); re == true {
				setMsg(w, "email", "Please enter a valid Email Address!")
			}
			if re := strings.Contains(e, "Fname"); re == true {
				setMsg(w, "fname", "Please enter a valid First Name")
			}
			if re := strings.Contains(e, "Username"); re == true {
				setMsg(w, "username", "Please enter a valid Username!")
			}
			if re := strings.Contains(e, "Password"); re == true {
				setMsg(w, "password", "Please enter a Password!")
			}

		}
		if r.FormValue("password") != r.FormValue("cpassword") {
			setMsg(w, "password", "The passwords you entered do not Match!")
			http.Redirect(w, r, "/signup", 302)
			return
		}

		if result == true {
			u.Password = enyptPass(u.Password)
			saveData(u)
			http.Redirect(w, r, "/", 302)
			return
		}
		http.Redirect(w, r, "/signup", 302)

	}
}

func render(w http.ResponseWriter, name string, data interface{}) {
	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	tmpl.ExecuteTemplate(w, name, data)
}

func main() {
	govalidator.SetFieldsRequiredByDefault(true)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir("files"))))
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/example", examplePage)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/test/", view)
	http.HandleFunc("/edit/", edit)
	http.HandleFunc("/save/", save)
	http.HandleFunc("/upload/", upload)
	http.ListenAndServe(":8000", nil)
}

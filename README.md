# Literary Lions

This project includes a live forum, where users can communicate.

In order to run the program, navigate to the folder with 

```cd literary-lions```

Once there, you can run it with 

```go run main.go```

and opening [localhost:5000](localhost:5000) in your browser.

## Functionalities

The webpage has many functionalities, including, but not limited to:

1. Cookies for session management
2. Ability to register
3. Ability to log in after registering
4. Option to create a post
5. Possibility to either like or dislike posts
6. Option to comment on posts
7. Possibility to either like or dislike posts
8. Possibility to search for posts by using keywords, as well as search inside a specific category
9. Option to filter posts by category
10. Possibility to edit your profile bio
11. Possibility to view other peoples profiles and see what they have posted and liked

and much more - try it and see!

## Dockerizing the application

In order to run the application with docker, you must first have docker installed (or have the extension in vscode).

After you have cloned the repository and have installed docker, you can build the application with 

```docker build -t literary-lions .``` or if you do not have root access ```sudo docker build -t literary-lions .```

After building the image, you can run it with

```docker run -p 5000:5000 literary-lions``` or if you do not have root access ```sudo docker run -p 5000:5000 literary-lions```

If you do not have root privileges within docker you might need to run the commands with sudo. 

For example:
instead of
```docker build -t literary-lions .```
you would run
```sudo docker build -t literary-lions .```

If you wish to be able to run the docker commands without sudo, you will need to add yourself to the docker user group.
Follow [these steps](https://docs.docker.com/engine/install/linux-postinstall/) in order to create the group and add yourself to it.


<img src="ERD.png" width="80%" height="80%">


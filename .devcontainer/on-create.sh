
install_python_packages(){
    pip install --root-user-action=ignore --upgrade pip
    pip install --root-user-action=ignore pip-tools
    pip install --root-user-action=ignore pre-commit

    pip-compile --resolver=backtracking --strip-extras requirements_test.in
    pip-compile --resolver=backtracking --strip-extras requirements.in

    pip install --root-user-action=ignore -r requirements_test.txt
}

setup_precommit(){
    pre-commit autoupdate
    pre-commit install
}

intall_git_bashprompt(){
    git clone https://github.com/magicmonty/bash-git-prompt.git $HOME/.bash-git-prompt --depth=1

    echo -e "if [ -f "$HOME/.bash-git-prompt/gitprompt.sh" ]
then
    GIT_PROMPT_ONLY_IN_REPO=1
    source $HOME/.bash-git-prompt/gitprompt.sh
fi\n" >> $HOME/.bashrc

}

configure_git(){

    if [[ ! -z $GIT_USER_NAME && ! -z $GIT_EMAIL && ! -z $GIT_COMMIT_EDITOR ]]
    then
        git config --global user.name "$GIT_USER_NAME"
        git config --global user.email "$GIT_EMAIL"
        git config --global --replace-all core.editor "$GIT_COMMIT_EDITOR"
    else
        echo "Skipping git configuration, one or more GIT variable is not set"
    fi
}

main(){
    intall_git_bashprompt
    configure_git
    install_python_packages
    setup_precommit
}

main

__razor_commands () {
    local IFS=$'\n'
    COMPREPLY=($(IFS=: compgen -S' ' -W "list-requires:list-provides:list-files:list-file-packages:list-package-files:what-requires:what-provides:import-yum:import-rpmdb:validate:update:diff:install:init:download" -- $1))
}

__razor_packages () {
    local IFS=$'\n'

    COMPREPLY=($(./razor list --only-names "$1*" | while read p; do echo "$p "; done))
}

__razor_upstream_packages () {
    local IFS=$'\n'

    COMPREPLY=($(RAZOR_REPO=rawhide.repo ./razor list --only-names "$1*" | while read p; do echo "$p "; done))
}

__razor_files() {
    COMPREPLY=($(./razor list-files "$1*"))
}

__razor_requires() {
    COMPREPLY=($(compgen -W "$(./razor list-requires)" -- $1))
}

__razor_provides() {
    COMPREPLY=($(compgen -W "$(./razor list-provides)" -- $1))
}

__razor() {
    local cur="${COMP_WORDS[COMP_CWORD]}"

    if [ $COMP_CWORD = 1 ]; then
	__razor_commands $cur
    else
	case "${COMP_WORDS[1]}" in
	    list-requires|list-provides|list-package-files)
		__razor_packages $cur ;;
	    list-files|list-file-packages) __razor_files $cur ;;
	    what-requires) __razor_requires $cur ;;
	    what-provides) __razor_provides $cur ;;
	    install|download) __razor_upstream_packages $cur ;;
	esac
    fi
}

complete -o nospace -F __razor razor

#!/bin/sh

import_rpm() {
    echo "<package name=\"$1\" version=\"$2\" build=\"$3\">"
    echo "  <properties>"

    rpm -q --provides $p | sort -u | while read name ignore version; do
	if test -z $version; then
	    echo "    <provides name=\"$name\"/>"
	else
	    echo "    <provides name=\"$name\" version=\"$version\"/>"
	fi
    done

    rpm -q --requires $p | sort -u | while read name ignore version; do
	if test -z $version; then
	    echo "    <requires name=\"$name\"/>"
	else
	    echo "    <requires name=\"$name\" version=\"$version\"/>"
	fi
    done

    echo "  </properties>"
    echo "</package>"
}

mkdir -p pkgs
rpm -qa | while read p; do
    name=${p%-*-*}
    vr=${p#$name-}
    version=${vr%-*}
    release=${vr#*-}

    echo $name - $version - $release
    import_rpm $name $version $release > pkgs/$name.rzr
done

#!/bin/sh

import_rpm() {
    echo "<package name=\"$1\" version=\"$2\" build=\"$3\">"
    echo "  <properties>"

    rpm -q --provides $p | sort -u | while read name ignore version; do
	echo "    <provides name=\"$name\"/>"
    done

    rpm -q --requires $p | sort -u | while read name ignore version; do
	echo "    <requires name=\"$name\"/>"
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

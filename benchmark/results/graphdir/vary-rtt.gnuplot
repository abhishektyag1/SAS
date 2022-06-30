    set terminal svg;
    set output 'vary-rtt.svg';

    set multiplot layout 2, 1;
    set xlabel '';
    set ylabel 'Latency for registering a key (sec)';
    set yrange [0:]
    set key left top
    set xtics ('0' 0, '10' 10, '20' 20, '40' 40, '80' 80, '160' 160, '320' 320);

    plot 

    set xlabel 'Round Trip Time (ms)';
    set ylabel 'Latency for filing an allegation (sec)';
    
    plot 

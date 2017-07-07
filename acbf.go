package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"

	"encoding/hex"

	"github.com/cheggaaa/pb"
	"github.com/shirou/gopsutil/cpu"
	"github.com/urfave/cli"
)

// 77214d4b196a87cd520045fd20a51d67
var audibleFixedKey = []byte{119, 33, 77, 75, 25, 106, 135, 205, 82, 0, 69, 253, 32, 165, 29, 103}
var wg sync.WaitGroup

// next index for cartesian product
func nextIndex(ix []int, lens int) {
	for j := len(ix) - 1; j >= 0; j-- {
		ix[j]++
		if j == 0 || ix[j] < lens {
			return
		}
		ix[j] = 0
	}
}

// calculate sha1 checksum from given activation bytes
func calculateChecksum(activationBytes []byte) []byte {
	h := sha1.New()
	h.Write(audibleFixedKey)      // audible fixed key
	h.Write(activationBytes)      // current activation bytes
	intermediateKey := h.Sum(nil) // intermediate key

	h = sha1.New()
	h.Write(audibleFixedKey)     // audible fixed key
	h.Write(intermediateKey)     // intermediate key
	h.Write(activationBytes)     // current activation bytes
	intermediateIv := h.Sum(nil) // intermediate iv

	h = sha1.New()
	h.Write(intermediateKey[0:16]) // first 16 bytes from intermediate key
	h.Write(intermediateIv[0:16])  // first 16 bytes from intermediate iv
	return h.Sum(nil)              // generated checksum
}

// worker go routine that consumes jobs
func worker(id int, cb *pb.ProgressBar, checksum []byte, jobs chan int, quit chan int, result chan<- []byte) {
	wg.Add(1)
	defer wg.Done()

	for job := range jobs {
		select {
		case <-quit:
			cb.Finish()
			// received kill signal
			return
		default:
			ab := make([]byte, 4)
			cb.Prefix(fmt.Sprintf("Block %3d | %02x000000-%02xffffff ", job, job, job))

			for ix := make([]int, 3); ix[0] < 256; nextIndex(ix, 256) {
				cb.Increment()
				ab[0] = byte(job)
				ab[1] = byte(ix[0])
				ab[2] = byte(ix[1])
				ab[3] = byte(ix[2])

				if bytes.Equal(checksum, calculateChecksum(ab)) {
					// send result
					result <- ab

					// send kill signal to remaining jobs
					for i := range jobs {
						quit <- i
					}
					cb.Finish()

					// get out
					return
				}
			}
		}
	}
}

// where it happens
func bruteforce(startpoint int, checksum []byte, cores int) {
	jobs := make(chan int, 256)
	quit := make(chan int, 256)
	result := make(chan []byte, 1)
	cpuInfo, _ := cpu.Info()

	pool, err := pb.StartPool()
	if err != nil {
		panic(err)
	}

	bars := make([]*pb.ProgressBar, cores)

	total := (256 - startpoint) * 256 * 256 * 256
	chunk := total / cores

	fmt.Println()
	fmt.Printf("> Checksum: %x\n", checksum)
	fmt.Printf("> CPU: %s (using %d/%d cores)\n", cpuInfo[0].ModelName, cores, cpuInfo[0].Cores)
	fmt.Printf("> Combinations: %d\n", total)
	fmt.Printf("> Combinations per Core: %d\n", chunk)
	fmt.Println()

	// spawn workers
	for w := 0; w < cores; w++ {
		bars[w] = pb.New(chunk)
		bars[w].ShowCounters = false
		pool.Add(bars[w])
		go worker(w, bars[w], checksum, jobs, quit, result)
	}

	// add up to 255 jobs
	for j := startpoint; j <= 255; j++ {
		jobs <- j
	}

	close(jobs)
	wg.Wait()
	pool.Stop()

	select {
	case bytesFound := <-result:
		fmt.Println()
		fmt.Printf("> Activation Bytes: %x\n", bytesFound)
	default:
		fmt.Println()
		fmt.Printf("> No Activation Bytes found!\n")
	}
}

// https://brandur.org/go-worker-pool
// https://groups.google.com/forum/#!topic/Golang-Nuts/zAmaq1Q2mqA
func main() {
	// get number of CPU cores
	cores := runtime.NumCPU()

	app := cli.NewApp()
	app.Name = "audible-checksum-bruteforcer"
	app.Usage = "Bruteforce the activation bytes of an audible audiobook from its checksum"
	app.Version = "0.1.0"
	app.HideHelp = true
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Richard Kuhnt",
			Email: "r15ch13+git@gmail.com",
		},
	}
	app.ArgsUsage = "<audiobook checksum as sha1 hash>"
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "start, s",
			Value: 0,
			Usage: "Set a startpoint to skip already calculated `block`s",
		},
		cli.IntFlag{
			Name:  "cores, c",
			Value: cores,
			Usage: "Limit amount of used CPU `cores`",
		},
	}

	app.Action = func(c *cli.Context) error {

		checksumArg := ""
		if c.NArg() == 1 {
			checksumArg = c.Args().Get(0)
		} else {
			cli.ShowAppHelp(c)
			return nil
		}

		isChecksum, _ := regexp.MatchString("[a-fA-F0-9]{40}", checksumArg)
		if !isChecksum {
			cli.ShowAppHelp(c)
			return nil
		}

		start := c.Int("start")
		if start < 0 || start > 255 {
			start = 0
		}

		coresArg := c.Int("cores")
		if coresArg < cores && coresArg >= 1 {
			cores = coresArg
		}

		checksum, err := hex.DecodeString(checksumArg)
		if err != nil {
			panic(err)
		}

		bruteforce(start, checksum, cores)
		return nil
	}

	app.Run(os.Args)
}
